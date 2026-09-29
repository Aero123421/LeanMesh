#include "core/member/discovery.hpp"

#include <algorithm>

#include "core/codec.hpp"
#include "security/crypto.hpp"

namespace lm::member {

// HMAC-SHA256 (RFC 2104) from the node's one SHA-256; the key is one block, so no key hashing is needed.
Status scope_tag(ByteView key, uint8_t kind, const std::array<uint8_t, 16> &nonce, const OfferHint &fields,
                 std::array<uint8_t, 8> &tag) {
    if (key.size() != k_scope_key_bytes) {
        return Status::InvalidArgument;
    }
    std::array<uint8_t, 8 + 1 + 16 + 1 + 4> msg{};
    Writer w{MutByteView{msg}};
    w.bytes(ByteView{reinterpret_cast<const uint8_t *>("LM1-DISC"), 8});
    w.u8(kind);
    w.bytes(ByteView{nonce});
    if (kind == k_obj_join_offer) {
        w.u8(fields.depth);
        w.u32be(fields.expected_revision);
    }
    LM_TRY(w.finish());
    std::array<uint8_t, 64> pad{};
    Sha256Digest inner{};
    Sha256Digest outer{};
    for (std::size_t i = 0; i < pad.size(); ++i) {
        pad[i] = static_cast<uint8_t>((i < key.size() ? key[i] : 0) ^ 0x36U);
    }
    Status st = sec::sha256_parts(ByteView{pad}, w.written(), inner);
    for (std::size_t i = 0; i < pad.size(); ++i) {
        pad[i] = static_cast<uint8_t>((i < key.size() ? key[i] : 0) ^ 0x5CU);
    }
    if (st == Status::Ok) {
        st = sec::sha256_parts(ByteView{pad}, ByteView{inner}, outer);
    }
    sec::secure_zero(MutByteView{pad});
    sec::secure_zero(MutByteView{inner});
    if (st == Status::Ok) {
        std::copy_n(outer.begin(), tag.size(), tag.begin());
    }
    return st;
}

bool scope_ok(ByteView key, uint8_t kind, const std::array<uint8_t, 16> &nonce, const OfferHint &hint) {
    if (key.empty()) {
        return true; // an unscoped node narrows nothing
    }
    std::array<uint8_t, 8> expect{};
    return hint.scoped && scope_tag(key, kind, nonce, hint, expect) == Status::Ok &&
           sec::ct_equal(ByteView{expect}, ByteView{hint.tag});
}

Status scope_sign(ByteView key, uint8_t kind, const std::array<uint8_t, 16> &nonce, OfferHint &hint) {
    hint.scoped = !key.empty();
    return hint.scoped ? scope_tag(key, kind, nonce, hint, hint.tag) : Status::Ok;
}

void Discovery::begin(MonoTime now, uint16_t jitter_ms, bool listen_first, Duration budget, bool auto_resume) {
    const Duration jitter = Duration::from_ms(jitter_ms % 400);
    phase_ = listen_first ? Phase::Listen : Phase::Hello;
    // Listen ends after 800 ms; the first hello follows after the jitter (both are timers, not polls).
    hello_at_ = now + (listen_first ? k_listen : Duration{}) + jitter;
    budget_ = budget;
    budget_end_ = now + budget;
    handshakes_ = 0;
    auto_resume_ = auto_resume;
    resume_at_ = MonoTime::never();
}

void Discovery::wake(MonoTime now, uint16_t jitter_ms) {
    if (phase_ == Phase::Idle) {
        return;
    }
    backoff_ = k_backoff_min;
    begin(now, jitter_ms, false, budget_, auto_resume_);
}

Discovery::Act Discovery::poll(MonoTime now) {
    switch (phase_) {
    case Phase::Idle:
        return Act::None;
    case Phase::Listen:
    case Phase::Hello:
        if (now >= budget_end_) {
            phase_ = Phase::Backoff;
            resume_at_ = now + backoff_;
            backoff_ = backoff_ + backoff_ > k_backoff_max ? k_backoff_max : backoff_ + backoff_;
            return Act::Exhausted;
        }
        if (now >= hello_at_) {
            phase_ = Phase::Hello;
            if (suppressed(now)) {
                hello_at_ = earliest(suppress_until_, budget_end_); // asked to stay quiet: sleep until then
                return Act::None;
            }
            hello_at_ = now + k_hello_gap;
            return Act::Hello;
        }
        return Act::None;
    case Phase::Backoff:
        if (auto_resume_ && now >= resume_at_) {
            begin(now, 0, false, budget_, true);
            return Act::Resumed;
        }
        return Act::None;
    }
    return Act::None;
}

MonoTime Discovery::deadline() const {
    switch (phase_) {
    case Phase::Idle:
        return MonoTime::never();
    case Phase::Listen:
    case Phase::Hello:
        return earliest(hello_at_, budget_end_);
    case Phase::Backoff:
        return auto_resume_ ? resume_at_ : MonoTime::never();
    }
    return MonoTime::never();
}

} // namespace lm::member
