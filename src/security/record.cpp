#include "security/record.hpp"

#include <psa/crypto.h>

#include <cstring>
#include <utility>

#include "core/codec.hpp"
#include "core/wire/cbor.hpp"
#include "security/crypto.hpp"

namespace lm::sec {

namespace {

constexpr std::size_t k_nonce_bytes = 12;

std::array<uint8_t, k_nonce_bytes> make_nonce(const DirectionKey &k, uint64_t counter) {
    std::array<uint8_t, k_nonce_bytes> n{};
    Writer w{MutByteView{n.data(), n.size()}};
    w.bytes(ByteView{k.prefix.data(), k.prefix.size()});
    w.u64be(counter);
    return n;
}

// Imports the 16-byte key for exactly one AES-GCM call and destroys it again, so a session holds
// key bytes only (zeroisable by us) and never occupies a PSA key slot between frames.
class OneShotKey {
  public:
    OneShotKey(const DirectionKey &k, psa_key_usage_t usage) {
        psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_VOLATILE);
        psa_set_key_type(&a, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&a, 128);
        psa_set_key_usage_flags(&a, usage);
        psa_set_key_algorithm(&a, PSA_ALG_GCM);
        status_ = psa_import_key(&a, k.key.data(), k.key.size(), &id_);
        psa_reset_key_attributes(&a);
    }
    ~OneShotKey() { (void)destroy(); }
    // Destroys the key (once; one retry). A key that cannot be destroyed is still live in PSA: the
    // caller must not report success for the operation it served (FIX1-D21).
    [[nodiscard]] psa_status_t destroy() {
        if (status_ != PSA_SUCCESS || destroyed_) {
            return PSA_SUCCESS;
        }
        psa_status_t st = psa_destroy_key(id_);
        if (st != PSA_SUCCESS) {
            st = psa_destroy_key(id_);
        }
        destroyed_ = st == PSA_SUCCESS || st == PSA_ERROR_INVALID_HANDLE;
        return destroyed_ ? PSA_SUCCESS : st;
    }
    OneShotKey(const OneShotKey &) = delete;
    OneShotKey &operator=(const OneShotKey &) = delete;
    [[nodiscard]] psa_status_t status() const { return status_; }
    [[nodiscard]] psa_key_id_t id() const { return id_; }

  private:
    psa_key_id_t id_ = PSA_KEY_ID_NULL;
    psa_status_t status_ = PSA_ERROR_GENERIC_ERROR;
    bool destroyed_ = false;
};

void wipe_direction(DirectionKey &k) {
    secure_zero(MutByteView{k.key.data(), k.key.size()});
    secure_zero(MutByteView{k.prefix.data(), k.prefix.size()});
}

} // namespace

Status context_encode(const SessionContext &c, MutByteView out, std::size_t &len) {
    if (c.purpose < Purpose::Link || c.purpose > Purpose::Usb) {
        return Status::InvalidArgument;
    }
    for (uint64_t g : {c.assignment_i.value(), c.assignment_r.value(), c.membership_i.value(),
                       c.membership_r.value()}) {
        if (g > k_u63_max) {
            return Status::InvalidArgument;
        }
    }
    wire::CborWriter w{out};
    w.array(12);
    w.text(wire::ascii("LM1"));
    w.uint(static_cast<uint8_t>(c.purpose));
    w.bytes(c.fleet.view());
    w.bytes(c.domain.view());
    w.bytes(c.initiator.view());
    w.bytes(c.responder.view());
    w.uint(c.assignment_i.value());
    w.uint(c.assignment_r.value());
    w.uint(c.membership_i.value());
    w.uint(c.membership_r.value());
    w.bytes(ByteView{c.credential_hash_i.data(), c.credential_hash_i.size()});
    w.bytes(ByteView{c.credential_hash_r.data(), c.credential_hash_r.size()});
    LM_TRY(w.finish() == Status::Ok ? Status::Ok : Status::BufferTooSmall);
    len = w.size();
    return Status::Ok;
}

Status context_hash(const SessionContext &ctx, Sha256Digest &out) {
    std::array<uint8_t, k_session_context_max_bytes> buf{};
    std::size_t len = 0;
    LM_TRY(context_encode(ctx, MutByteView{buf.data(), buf.size()}, len));
    return sha256(ByteView{buf.data(), len}, out);
}

Status derive_record_keys(ByteView seed, const Sha256Digest &ctx_hash, Purpose purpose,
                          bool local_is_initiator, RecordKeys &out) {
    if (seed.size() != 32 || purpose < Purpose::Link || purpose > Purpose::Usb) {
        return Status::InvalidArgument;
    }
    // direction 0 = initiator -> responder: the initiator transmits on 0, the responder on 1.
    for (uint8_t dir = 0; dir < 2; ++dir) {
        std::array<uint8_t, 10 + 2 + 32> info{};
        Writer w{MutByteView{info.data(), info.size()}};
        w.bytes(wire::ascii("LM1-RECORD"));
        w.u8(static_cast<uint8_t>(purpose));
        w.u8(dir);
        w.bytes(ByteView{ctx_hash.data(), ctx_hash.size()});
        LM_TRY(w.finish());

        std::array<uint8_t, 20> okm{};
        psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
        psa_status_t st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        if (st == PSA_SUCCESS) {
            st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, ctx_hash.data(),
                                                ctx_hash.size());
        }
        if (st == PSA_SUCCESS) {
            st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, seed.data(),
                                                seed.size());
        }
        if (st == PSA_SUCCESS) {
            st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info.data(),
                                                info.size());
        }
        if (st == PSA_SUCCESS) {
            st = psa_key_derivation_output_bytes(&op, okm.data(), okm.size());
        }
        psa_key_derivation_abort(&op);
        if (st != PSA_SUCCESS) {
            secure_zero(MutByteView{okm.data(), okm.size()});
            return from_psa(st);
        }
        const bool is_tx = (dir == 0) == local_is_initiator;
        DirectionKey &d = is_tx ? out.tx : out.rx;
        for (std::size_t i = 0; i < 16; ++i) {
            d.key[i] = okm[i];
        }
        for (std::size_t i = 0; i < 4; ++i) {
            d.prefix[i] = okm[16 + i];
        }
        secure_zero(MutByteView{okm.data(), okm.size()});
    }
    return Status::Ok;
}

ReplayVerdict ReplayWindow::check(uint64_t counter) const {
    if (counter == 0) {
        return ReplayVerdict::Reserved;
    }
    if (counter > highest_) {
        return ReplayVerdict::Fresh;
    }
    const uint64_t behind = highest_ - counter;
    if (behind >= 64) {
        return ReplayVerdict::TooOld;
    }
    return ((seen_ >> behind) & 1U) != 0 ? ReplayVerdict::Duplicate : ReplayVerdict::Fresh;
}

void ReplayWindow::commit(uint64_t counter) {
    if (check(counter) != ReplayVerdict::Fresh) {
        return; // callers commit only after check() said Fresh; anything else is ignored
    }
    if (counter > highest_) {
        const uint64_t shift = counter - highest_;
        seen_ = shift >= 64 ? 0 : (seen_ << shift);
        seen_ |= 1U;
        highest_ = counter;
    } else {
        seen_ |= 1ULL << (highest_ - counter);
    }
}

Status link_aad(ByteView header24, const Sha256Digest &ctx_hash,
                std::array<uint8_t, k_link_aad_bytes> &out) {
    if (header24.size() != 24) {
        return Status::InvalidArgument;
    }
    Writer w{MutByteView{out.data(), out.size()}};
    w.bytes(header24);
    w.bytes(ByteView{ctx_hash.data(), ctx_hash.size()});
    return w.finish();
}

Status end_aad(const Sha256Digest &ctx_hash, RootTerm root_term, ByteView header42,
               std::array<uint8_t, k_end_aad_bytes> &out) {
    if (header42.size() != 42) {
        return Status::InvalidArgument;
    }
    Writer w{MutByteView{out.data(), out.size()}};
    w.bytes(wire::ascii("LM1-END"));
    w.bytes(ByteView{ctx_hash.data(), ctx_hash.size()});
    w.u32be(root_term.value());
    w.bytes(header42);
    return w.finish();
}

void RecordKeys::wipe() {
    wipe_direction(tx);
    wipe_direction(rx);
}

Status RecordSession::install(RecordKeys &&keys) {
    if (active_) {
        return Status::Conflict;
    }
    keys_ = std::move(keys);
    window_.reset();
    tx_reserved_ = 0;
    tx_sealed_ = 0;
    active_ = true;
    return Status::Ok;
}

void RecordSession::take(RecordSession &o) {
    keys_ = std::move(o.keys_);
    window_ = o.window_;
    tx_reserved_ = o.tx_reserved_;
    tx_sealed_ = o.tx_sealed_;
    active_ = o.active_;
    o.wipe();
}

void RecordSession::wipe() {
    wipe_direction(keys_.tx);
    wipe_direction(keys_.rx);
    window_.reset();
    tx_reserved_ = 0;
    tx_sealed_ = 0;
    active_ = false;
}

Status RecordSession::next_counter(uint64_t &counter) {
    if (!active_) {
        return Status::RecoveryRequired;
    }
    if (tx_reserved_ >= k_max_records_per_key) {
        return Status::SessionRefreshRequired;
    }
    counter = ++tx_reserved_;
    return Status::Ok;
}

Status RecordSession::seal(uint64_t counter, ByteView aad, ByteView plaintext, MutByteView out) {
    if (!active_) {
        return Status::RecoveryRequired;
    }
    // Each reserved counter is sealed at most once and in increasing order: content that changes
    // (new path, new payload) always gets a fresh counter, never a re-encryption under an old nonce.
    if (counter == 0 || counter > tx_reserved_ || counter <= tx_sealed_) {
        return Status::InvalidArgument;
    }
    if (out.size() < plaintext.size() + k_aead_tag_bytes) {
        return Status::BufferTooSmall;
    }
    tx_sealed_ = counter;
    OneShotKey key{keys_.tx, PSA_KEY_USAGE_ENCRYPT};
    LM_TRY(from_psa(key.status()));
    const auto nonce = make_nonce(keys_.tx, counter);
    std::size_t len = 0;
    const psa_status_t enc = psa_aead_encrypt(key.id(), PSA_ALG_GCM, nonce.data(), nonce.size(),
                                              aad.data(), aad.size(), plaintext.data(),
                                              plaintext.size(), out.data(), out.size(), &len);
    if (key.destroy() != PSA_SUCCESS) {
        secure_zero(out); // the key is still live: do not hand out a "sealed" frame
        return Status::RecoveryRequired;
    }
    LM_TRY(from_psa(enc));
    return len == plaintext.size() + k_aead_tag_bytes ? Status::Ok : Status::RecoveryRequired;
}

Status RecordSession::open(uint64_t counter, ByteView aad, ByteView ciphertext,
                           MutByteView plaintext, std::size_t &plaintext_len,
                           ReplayVerdict &verdict) {
    plaintext_len = 0;
    verdict = window_.check(counter);
    if (!active_) {
        return Status::RecoveryRequired;
    }
    if (verdict == ReplayVerdict::Reserved || ciphertext.size() < k_aead_tag_bytes) {
        return Status::BadFrame;
    }
    if (counter > k_max_records_per_key) {
        return Status::SessionRefreshRequired;
    }
    if (verdict == ReplayVerdict::TooOld) {
        return Status::Replay; // dropped before any crypto: an old packet is not worth an AEAD
    }
    if (plaintext.size() < ciphertext.size() - k_aead_tag_bytes) {
        return Status::BufferTooSmall;
    }
    OneShotKey key{keys_.rx, PSA_KEY_USAGE_DECRYPT};
    LM_TRY(from_psa(key.status()));
    const auto nonce = make_nonce(keys_.rx, counter);
    std::size_t len = 0;
    const psa_status_t dec = psa_aead_decrypt(key.id(), PSA_ALG_GCM, nonce.data(), nonce.size(),
                                              aad.data(), aad.size(), ciphertext.data(),
                                              ciphertext.size(), plaintext.data(),
                                              plaintext.size(), &len);
    if (key.destroy() != PSA_SUCCESS) {
        secure_zero(plaintext);
        return Status::RecoveryRequired;
    }
    LM_TRY(from_psa(dec));
    plaintext_len = len;
    if (verdict == ReplayVerdict::Duplicate) {
        return Status::Replay; // authentic duplicate: the caller may re-ACK, never re-apply
    }
    return Status::Ok;
}

Status RecordSession::open_in_place(uint64_t counter, ByteView aad, MutByteView sealed,
                                    std::size_t &plaintext_len, ReplayVerdict &verdict) {
    plaintext_len = 0;
    verdict = window_.check(counter);
    if (!active_) {
        return Status::RecoveryRequired;
    }
    if (verdict == ReplayVerdict::Reserved || sealed.size() < k_aead_tag_bytes) {
        return Status::BadFrame;
    }
    if (counter > k_max_records_per_key) {
        return Status::SessionRefreshRequired;
    }
    if (verdict == ReplayVerdict::TooOld) {
        return Status::Replay; // dropped before any crypto: an old packet is not worth an AEAD
    }
    OneShotKey key{keys_.rx, PSA_KEY_USAGE_DECRYPT};
    LM_TRY(from_psa(key.status()));
    const auto nonce = make_nonce(keys_.rx, counter);
    const std::size_t ct_len = sealed.size() - k_aead_tag_bytes;
    // Chunks are whole AES blocks, so one update never outputs more than it consumed: the plaintext
    // written back (w) never overtakes the ciphertext still to be read (r).
    std::array<uint8_t, 64 + 16> bounce{};
    std::size_t w = 0;
    psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
    psa_status_t st = psa_aead_decrypt_setup(&op, key.id(), PSA_ALG_GCM);
    if (st == PSA_SUCCESS) {
        st = psa_aead_set_nonce(&op, nonce.data(), nonce.size());
    }
    if (st == PSA_SUCCESS) {
        st = psa_aead_update_ad(&op, aad.data(), aad.size());
    }
    for (std::size_t r = 0; st == PSA_SUCCESS && r < ct_len; r += 64) {
        const std::size_t n = ct_len - r < 64 ? ct_len - r : 64;
        std::size_t out = 0;
        st = psa_aead_update(&op, sealed.data() + r, n, bounce.data(), bounce.size(), &out);
        if (st == PSA_SUCCESS && w + out <= r + n) {
            std::memcpy(sealed.data() + w, bounce.data(), out);
            w += out;
        } else if (st == PSA_SUCCESS) {
            st = PSA_ERROR_CORRUPTION_DETECTED; // would overwrite unread ciphertext: never
        }
    }
    if (st == PSA_SUCCESS) {
        std::size_t out = 0;
        st = psa_aead_verify(&op, bounce.data(), bounce.size(), &out, sealed.data() + ct_len,
                             k_aead_tag_bytes);
        if (st == PSA_SUCCESS && w + out <= ct_len) {
            std::memcpy(sealed.data() + w, bounce.data(), out);
            w += out;
        } else if (st == PSA_SUCCESS) {
            st = PSA_ERROR_CORRUPTION_DETECTED;
        }
    }
    psa_aead_abort(&op);
    secure_zero(MutByteView{bounce.data(), bounce.size()});
    if (key.destroy() != PSA_SUCCESS) {
        st = PSA_ERROR_CORRUPTION_DETECTED; // the key is still live: do not report an opened record
    }
    if (st != PSA_SUCCESS || w != ct_len) {
        secure_zero(sealed.first(w)); // unauthenticated plaintext is never left behind
        return st == PSA_SUCCESS ? Status::RecoveryRequired : from_psa(st);
    }
    plaintext_len = w;
    if (verdict == ReplayVerdict::Duplicate) {
        return Status::Replay; // authentic duplicate: the caller may re-ACK, never re-apply
    }
    return Status::Ok;
}

} // namespace lm::sec
