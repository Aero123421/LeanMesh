// LM1 record layer (docs/06 §4-6, docs/09 §2/§4): session context and ctx_hash, record key
// derivation from the EDHOC exporter seed, AES-128-GCM sealing with counter nonces, and the
// 64-packet replay window. Symmetric only, so it may run on the mesh owner (one short PSA AES-GCM
// call per frame); no public-key operation and no Flash access happens here.
//
// This layer never decides authorisation: it proves "this ciphertext was sealed by the peer of this
// exact context at this counter". Identity, generation and SID checks stay with the callers.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"

namespace lm::sec {

enum class Purpose : uint8_t { Link = 1, End = 2, Usb = 3 };

// Everything that binds a session to its identities (docs/06 §4). Different purpose, domain or any
// generation gives a different ctx_hash and therefore different keys.
struct SessionContext {
    Purpose purpose = Purpose::Link;
    FleetId fleet;
    DomainId domain;
    DeviceId initiator;
    DeviceId responder;
    AssignmentGen assignment_i;
    AssignmentGen assignment_r;
    MembershipGen membership_i;
    MembershipGen membership_r;
    Sha256Digest credential_hash_i{};
    Sha256Digest credential_hash_r{};
};

inline constexpr std::size_t k_session_context_max_bytes = 224;

// Deterministic CBOR ["LM1", purpose, fleet, domain, dev_i, dev_r, asg_i, asg_r, mem_i, mem_r,
// cred_hash_i, cred_hash_r]. InvalidArgument for a generation above u63.
[[nodiscard]] Status context_encode(const SessionContext &ctx, MutByteView out, std::size_t &len);
[[nodiscard]] Status context_hash(const SessionContext &ctx, Sha256Digest &out);

// One direction of a session. `key` is the AES-128-GCM key, `prefix` the first four nonce bytes.
struct DirectionKey {
    std::array<uint8_t, 16> key{};
    std::array<uint8_t, 4> prefix{};
};

// Move-only secret material with a zeroising destructor: keys travel handshake -> session by
// move, leaving the source zeroed, so no stray plaintext copy survives (FIX1-D1/D19). Copying a
// key set would let two sessions share one TX counter space (AES-GCM nonce reuse).
struct RecordKeys {
    DirectionKey tx;
    DirectionKey rx;

    RecordKeys() = default;
    RecordKeys(const RecordKeys &) = delete;
    RecordKeys &operator=(const RecordKeys &) = delete;
    RecordKeys(RecordKeys &&o) noexcept : tx(o.tx), rx(o.rx) { o.wipe(); }
    RecordKeys &operator=(RecordKeys &&o) noexcept {
        if (this != &o) {
            tx = o.tx;
            rx = o.rx;
            o.wipe();
        }
        return *this;
    }
    ~RecordKeys() { wipe(); }
    void wipe();
};

// seed = EDHOC_Exporter(40000, ctx_hash, 32). PRK = HKDF-Extract(salt = ctx_hash, seed);
// key||prefix = HKDF-Expand(PRK, "LM1-RECORD" || purpose || direction || ctx_hash, 20). Direction
// 0 is initiator -> responder, 1 the reverse.
[[nodiscard]] Status derive_record_keys(ByteView seed, const Sha256Digest &ctx_hash, Purpose purpose,
                                        bool local_is_initiator, RecordKeys &out);

enum class ReplayVerdict : uint8_t {
    Fresh,     // never seen, inside or ahead of the window
    Duplicate, // inside the window and already accepted
    TooOld,    // 64 or more behind the highest accepted counter
    Reserved,  // counter 0 is never valid
};

// Sliding window of the 64 most recent counters. check() never changes state; commit() is called
// only after the AEAD tag verified and the caller's own destination/length checks passed (docs/06 §6).
class ReplayWindow {
  public:
    [[nodiscard]] ReplayVerdict check(uint64_t counter) const;
    void commit(uint64_t counter);
    void reset() { *this = ReplayWindow{}; }
    [[nodiscard]] uint64_t highest() const { return highest_; }

  private:
    uint64_t highest_ = 0;
    uint64_t seen_ = 0; // bit i set: counter (highest_ - i) was accepted
};

// Traffic keys are replaced after 2^24 records or one hour, whichever comes first (docs/06 §7). The
// count is enforced here; the hour belongs to the session owner, which has the clock.
inline constexpr uint64_t k_max_records_per_key = 1ULL << 24;

constexpr std::size_t k_aead_tag_bytes = 16;
constexpr std::size_t k_link_aad_bytes = 24 + 32;
constexpr std::size_t k_end_aad_bytes = 7 + 32 + 4 + 42;

// AAD of the link layer: prefix24 || ctx_hash (docs/09 §2).
[[nodiscard]] Status link_aad(ByteView header24, const Sha256Digest &ctx_hash,
                              std::array<uint8_t, k_link_aad_bytes> &out);
// AAD of the end record: "LM1-END" || ctx_hash || u32be(root_term) || header42 (docs/09 §4).
[[nodiscard]] Status end_aad(const Sha256Digest &ctx_hash, RootTerm root_term, ByteView header42,
                             std::array<uint8_t, k_end_aad_bytes> &out);

// Owns one key set and its TX counter / replay window. Move-only: a copy would fork the counter
// (nonce reuse) and the replay window. A moved-from session is wiped and inactive.
class RecordSession {
  public:
    RecordSession() = default;
    RecordSession(const RecordSession &) = delete;
    RecordSession &operator=(const RecordSession &) = delete;
    RecordSession(RecordSession &&o) noexcept { take(o); }
    RecordSession &operator=(RecordSession &&o) noexcept {
        if (this != &o) {
            wipe();
            take(o);
        }
        return *this;
    }
    ~RecordSession() { wipe(); }

    // Takes ownership of freshly derived keys (zeroing `keys`): counters start at 1, the window is
    // empty. Conflict while the session is active: keys are one-shot and tied to one EDHOC
    // context, so wipe() (or a new session object) is required first, never a silent counter reset.
    [[nodiscard]] Status install(RecordKeys &&keys);
    // Zeroises keys and state. Idempotent.
    void wipe();
    [[nodiscard]] bool active() const { return active_; }

    // Reserves the next transmit counter (1, 2, ...). Never wraps: SessionRefreshRequired once
    // 2^24 records were used, RecoveryRequired if the session holds no keys. A reserved counter is
    // consumed even when sealing fails, so a nonce is never reused.
    [[nodiscard]] Status next_counter(uint64_t &counter);
    // Seals `plaintext` with a counter obtained from next_counter(), strictly increasing per call
    // (each counter is sealed at most once). out = ciphertext || tag, size = plaintext + 16.
    [[nodiscard]] Status seal(uint64_t counter, ByteView aad, ByteView plaintext, MutByteView out);
    // seal() for large records without a second buffer: buf[0, buf.size() - 16) holds the plaintext
    // and is replaced by ciphertext, the tag follows it. Same counter rule as seal(); chunked through
    // a small stack buffer for the same PSA no-overlap reason as open_in_place().
    [[nodiscard]] Status seal_in_place(uint64_t counter, ByteView aad, MutByteView buf);

    // Verifies and decrypts. Ok only for a fresh, authentic record. The window is NOT advanced: the
    // caller runs its destination/length/identity checks on the plaintext and then calls accept()
    // (docs/06 §6 "AEAD成功と宛先/長さ検査前にwindowを消費しない").
    //  - Replay + verdict Duplicate: authentic, already accepted. Never apply it twice.
    //  - Replay + verdict TooOld: outside the window (not even authenticated).
    //  - AuthRejected: tag mismatch (also "same counter, different payload"); window untouched.
    //  - BadFrame: counter 0 or ciphertext shorter than a tag.
    // `plaintext` must hold ciphertext.size() - 16 bytes; plaintext_len receives that length.
    [[nodiscard]] Status open(uint64_t counter, ByteView aad, ByteView ciphertext,
                              MutByteView plaintext, std::size_t &plaintext_len,
                              ReplayVerdict &verdict);

    // open() for large records without a second buffer: `sealed` (ciphertext || tag) is replaced
    // by the plaintext (its first plaintext_len bytes) in place. Same results and window rule as
    // open(); on any failure the bytes written so far are zeroed, so unauthenticated plaintext
    // never stays. PSA forbids overlapping input and output (MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS
    // on IDF), so the record is decrypted in chunks through a small stack buffer and copied back
    // behind the read position.
    [[nodiscard]] Status open_in_place(uint64_t counter, ByteView aad, MutByteView sealed,
                                       std::size_t &plaintext_len, ReplayVerdict &verdict);

    // Consumes `counter` in the replay window after open() returned Ok and the checks passed.
    void accept(uint64_t counter) { window_.commit(counter); }

    [[nodiscard]] uint64_t tx_used() const { return tx_reserved_; }
    [[nodiscard]] const ReplayWindow &window() const { return window_; }

  private:
    void take(RecordSession &o);

    RecordKeys keys_{};
    ReplayWindow window_;
    uint64_t tx_reserved_ = 0;
    uint64_t tx_sealed_ = 0;
    bool active_ = false;
};

} // namespace lm::sec
