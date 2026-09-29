#include "core/ota/ota.hpp"

#if defined(LM_OTA)

#include <algorithm>
#include <cstring>

#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"

namespace lm::ota {
namespace {

using wire::CborReader;

bool text_is(ByteView v, const char *s) {
    return v.size() == std::strlen(s) && std::memcmp(v.data(), s, v.size()) == 0;
}

Status decode_manifest(ByteView data, Manifest &out) {
    CborReader r{data};
    Manifest m;
    (void)r.array(10, 10);
    const ByteView soc = r.tstr(7, 7);
    if (text_is(soc, "esp32c3")) {
        m.soc = Soc::Esp32c3;
    } else if (text_is(soc, "esp32s3")) {
        m.soc = Soc::Esp32s3;
    } else if (text_is(soc, "esp32c5")) {
        m.soc = Soc::Esp32c5;
    } else if (text_is(soc, "esp32c6")) {
        m.soc = Soc::Esp32c6;
    } else {
        return Status::BadFrame;
    }
    const ByteView board = r.tstr(1, k_text_max);
    m.image_bytes = static_cast<uint32_t>(r.uint_in(1, k_max_image_bytes));
    const ByteView sha = r.bstr(32, 32);
    const ByteView version = r.tstr(1, k_text_max);
    m.security_version = static_cast<uint32_t>(r.uint_in(0, 0xFFFFFFFFULL));
    m.schema_min = static_cast<uint32_t>(r.uint_in(0, 0xFFFFFFFFULL));
    m.schema_max = static_cast<uint32_t>(r.uint_in(0, 0xFFFFFFFFULL));
    m.loader_min = static_cast<uint32_t>(r.uint_in(0, 0xFFFFFFFFULL));
    (void)r.uint_in(k_block_bytes, k_block_bytes); // block-bytes is fixed at 4096
    LM_TRY(r.finish());
    if (m.schema_min > m.schema_max) {
        return Status::BadFrame;
    }
    std::copy(board.begin(), board.end(), m.board.begin());
    m.board_len = static_cast<uint8_t>(board.size());
    std::copy(version.begin(), version.end(), m.version.begin());
    m.version_len = static_cast<uint8_t>(version.size());
    std::copy(sha.begin(), sha.end(), m.image_sha.begin());
    out = m;
    return Status::Ok;
}

Check refuse(Status s, Reject why) { return Check{s, why}; }

void put32(uint8_t *p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24U);
    p[1] = static_cast<uint8_t>(v >> 16U);
    p[2] = static_cast<uint8_t>(v >> 8U);
    p[3] = static_cast<uint8_t>(v);
}
uint32_t get32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24U) | (static_cast<uint32_t>(p[1]) << 16U) |
           (static_cast<uint32_t>(p[2]) << 8U) | p[3];
}

} // namespace

Check check_manifest(const member::TrustAnchor &trust, ByteView cose, const Device &dev, const State &state,
                     Manifest &out, Sha256Digest &manifest_hash) {
    if (dev.slot_bytes == 0) {
        return refuse(Status::Unsupported, Reject::NoSlot); // no second app slot: never made room by shrinking identity
    }
    member::Envelope env;
    ByteView data;
    const Status opened = member::open_signed(cose, trust.key, k_type_manifest, env, data);
    if (opened == Status::BadFrame) {
        return refuse(Status::BadFrame, Reject::Format);
    }
    if (opened != Status::Ok || env.domain != DomainId{}) { // a manifest is fleet-level: signed by the fleet, no domain
        return refuse(Status::AuthRejected, Reject::Signature);
    }
    Manifest m;
    if (decode_manifest(data, m) != Status::Ok) {
        return refuse(Status::BadFrame, Reject::Format);
    }
    if (m.soc != dev.soc) {
        return refuse(Status::Unsupported, Reject::Soc);
    }
    if (m.board_len != dev.board.size() || std::memcmp(m.board.data(), dev.board.data(), m.board_len) != 0) {
        return refuse(Status::Unsupported, Reject::Board);
    }
    if (m.image_bytes > std::min<uint32_t>(dev.slot_bytes, static_cast<uint32_t>(k_max_image_bytes))) {
        return refuse(Status::Unsupported, Reject::TooBig);
    }
    if (m.security_version < std::max(state.floor(), dev.running_security)) {
        return refuse(Status::AuthRejected, Reject::Downgrade); // validly signed, but older than what this device already ran
    }
    if (dev.storage_schema < m.schema_min || dev.storage_schema > m.schema_max) {
        return refuse(Status::Unsupported, Reject::Schema);
    }
    if (dev.loader < m.loader_min) {
        return refuse(Status::Unsupported, Reject::Loader);
    }
    Sha256Digest h{};
    if (sec::sha256(cose, h) != Status::Ok) {
        return refuse(Status::RecoveryRequired, Reject::Format);
    }
    if (state.has_failed() && state.failed() == m.image_sha) {
        return refuse(Status::Conflict, Reject::Retry); // this image already failed here (a re-signed copy is the same image)
    }
    out = m;
    manifest_hash = h;
    return Check{};
}

Status State::stage(const Manifest &m, const Sha256Digest &manifest_hash, uint8_t inactive_slot) {
    if (phase_ != Phase::Idle) {
        return Status::Busy;
    }
    if (inactive_slot > 1) {
        return Status::InvalidArgument;
    }
    if (has_failed_ && failed_ == m.image_sha) {
        return Status::Conflict;
    }
    phase_ = Phase::Staged;
    slot_ = inactive_slot;
    candidate_ = m.security_version;
    manifest_ = manifest_hash;
    image_ = m.image_sha;
    return Status::Ok;
}

Status State::arm() {
    if (phase_ != Phase::Staged) {
        return Status::Conflict;
    }
    phase_ = Phase::Armed;
    return Status::Ok;
}

Status State::boot_new() {
    if (phase_ != Phase::Armed) {
        return Status::Conflict;
    }
    phase_ = Phase::Pending;
    return Status::Ok;
}

Status State::confirm() {
    if (phase_ != Phase::Pending) {
        return Status::Conflict;
    }
    floor_ = std::max(floor_, candidate_);
    phase_ = Phase::Idle;
    slot_ = 0;
    candidate_ = 0;
    manifest_ = {};
    image_ = {};
    return Status::Ok;
}

void State::abandon(bool remember_failed) {
    if (remember_failed && phase_ != Phase::Idle) {
        failed_ = image_;
        has_failed_ = true;
    }
    phase_ = Phase::Idle;
    slot_ = 0;
    candidate_ = 0;
    manifest_ = {};
    image_ = {};
}

Status State::encode(MutByteView out, std::size_t &len) const {
    if (out.size() < k_encoded_bytes) {
        return Status::BufferTooSmall;
    }
    uint8_t *p = out.data();
    p[0] = k_version;
    p[1] = static_cast<uint8_t>(phase_);
    p[2] = slot_;
    p[3] = has_failed_ ? 1 : 0;
    put32(p + 4, floor_);
    put32(p + 8, candidate_);
    std::memcpy(p + 12, manifest_.data(), 32);
    std::memcpy(p + 44, image_.data(), 32);
    std::memcpy(p + 76, failed_.data(), 32);
    len = k_encoded_bytes;
    return Status::Ok;
}

Status State::decode(ByteView in, State &out) {
    if (in.size() != k_encoded_bytes || in[0] != k_version || in[1] > 3 || in[2] > 1 || in[3] > 1) {
        return Status::BadFrame;
    }
    State s;
    s.phase_ = static_cast<Phase>(in[1]);
    s.slot_ = in[2];
    s.has_failed_ = in[3] == 1;
    s.floor_ = get32(in.data() + 4);
    s.candidate_ = get32(in.data() + 8);
    std::memcpy(s.manifest_.data(), in.data() + 12, 32);
    std::memcpy(s.image_.data(), in.data() + 44, 32);
    std::memcpy(s.failed_.data(), in.data() + 76, 32);
    const bool idle = s.phase_ == Phase::Idle;
    if ((idle && (s.candidate_ != 0 || s.slot_ != 0)) || (!idle && s.candidate_ < s.floor_)) {
        return Status::BadFrame; // a record that no transition of this module can have written
    }
    out = s;
    return Status::Ok;
}

BootAction on_boot(const State &state, const BootFacts &f) {
    const bool on_new = f.running_slot == state.slot(); // two slots: the slot names the image
    switch (state.phase()) {
    case Phase::Idle:
        return BootAction::None;
    case Phase::Staged:
        return BootAction::Restart; // the running image is the old one whatever the facts say: the boot target was never set
    case Phase::Armed:
    case Phase::Pending:
        if (f.running_marked_invalid || !on_new) {
            // Armed: the switch never happened. Pending: the bootloader put the old image back. Either way the old image
            // is what runs; the difference is only whether the new one was ever started.
            return state.phase() == Phase::Armed ? BootAction::Abandon : BootAction::RolledBack;
        }
        if (state.phase() == Phase::Armed || f.running_pending_verify) {
            return BootAction::SelfTest; // first boot of the new image (Armed -> Pending is committed by the caller)
        }
        return BootAction::Finalize; // new image, already marked valid, floor not raised yet
    }
    return BootAction::None;
}

} // namespace lm::ota

#endif // LM_OTA
