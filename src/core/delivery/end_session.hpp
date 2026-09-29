// End sessions (EDHOC purpose 2, docs/06 §4-§6, docs/09 §4): the keys that protect a record from
// the origin device to the destination device. Relays never see them. One session per peer
// identity; a session is bound to the peers' full identities and generations (its ctx_hash), and
// the route origin/final of every record is checked against the peer's address in its
// MemberCredential. The SID is a receiver-assigned lookup handle and never authorises anything.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/delivery/route_spec.hpp"
#include "core/delivery/types.hpp"
#include "core/profile.hpp"
#include "core/time.hpp"
#include "security/record.hpp"

namespace lm::delivery {

struct EndSession {
    bool used = false;
    DeviceId peer;
    ShortAddr peer_addr; // lookup hint from the peer's verified MemberCredential
    AssignmentGen peer_assignment;
    MembershipGen peer_membership;
    sec::RecordSession rec;
    Sha256Digest ctx_hash{};
    uint32_t rx_sid = 0; // ours: the peer puts it into records addressed to us
    uint32_t tx_sid = 0; // the peer's: we put it into records addressed to it
    MonoTime valid_until = MonoTime::never();
    RootTime peer_lease; // SEC-D3: the peer credential's lease (the exchange caps valid_until by it and revalidates)
    uint32_t last_use = 0;
    uint32_t epoch = 0;     // changes with every installed session: sealed records remember it
    bool suspect = false;   // a whole message got no answer: the peer may have lost this session
    // The way back to the peer is not kept here: the reverse of every authenticated route from it
    // goes into the node's route table (Delivery, ARCH-D4).

    // In place (no temporary on the owner stack); the keys are zeroised first.
    void wipe() {
        rec.wipe();
        used = false;
        peer = DeviceId{};
        peer_addr = ShortAddr{};
        peer_assignment = AssignmentGen{};
        peer_membership = MembershipGen{};
        ctx_hash = Sha256Digest{};
        rx_sid = tx_sid = 0;
        valid_until = MonoTime::never();
        peer_lease = RootTime{};
        last_use = epoch = 0;
        suspect = false;
    }
};

class EndSessions {
  public:
    static constexpr std::size_t k_capacity = k_build_limits.end_sessions;

    [[nodiscard]] EndSession *find_peer(const DeviceId &d);
    [[nodiscard]] EndSession *find_addr(ShortAddr a); // [S11] by the lookup hint of a verified credential
    [[nodiscard]] EndSession *find_rx_sid(uint32_t sid);
    [[nodiscard]] bool sid_in_use(uint32_t sid) const;
    // A free entry, else the least recently used one is wiped and reused (its peer only needs a
    // new handshake). `keep` (may be null) is never chosen.
    [[nodiscard]] EndSession &acquire(const EndSession *keep = nullptr);
    void remove(EndSession &s) { s.wipe(); }
    void clear() {
        for (EndSession &s : slots_) {
            s.wipe();
        }
    }
    void touch(EndSession &s) { s.last_use = ++tick_; }
    // Distinguishes one installed session from the next of the same peer (records remember it).
    [[nodiscard]] uint32_t next_epoch() { return ++epoch_; }
    // Every installed session; `f` may remove the one it is given (SEC-D3 revalidation).
    template <class F> void for_each_used(F &&f) {
        for (EndSession &s : slots_) {
            if (s.used) {
                f(s);
            }
        }
    }
    [[nodiscard]] std::size_t count() const;
    template <class F> void for_each_active(F &&f) const { // [S16]
        for (const EndSession &s : slots_) {
            if (s.used && s.rec.active()) {
                f(s);
            }
        }
    }

  private:
    std::array<EndSession, k_capacity> slots_{};
    uint32_t tick_ = 0;
    uint32_t epoch_ = 0;
};

// Seals one end record into `out` (header42 || ciphertext || tag16). `h` supplies message id,
// port, kind, flags, expiry and is completed with `sid` (the peer's SID for ordinary records, our
// own for SESSION_BIND/ACK), the next counter and the plaintext length. AAD binds the ctx hash and
// the root term of the route header. The (rec, ctx_hash) form serves a session still being bound.
[[nodiscard]] Status seal_end_record(sec::RecordSession &rec, const Sha256Digest &ctx_hash,
                                     uint32_t sid, RootTerm term, wire::EndHeader h, ByteView plain,
                                     MutByteView out, std::size_t &len);
[[nodiscard]] inline Status seal_end_record(EndSession &s, uint32_t sid, RootTerm term,
                                            wire::EndHeader h, ByteView plain, MutByteView out,
                                            std::size_t &len) {
    return seal_end_record(s.rec, s.ctx_hash, sid, term, h, plain, out, len);
}

struct OpenedEnd {
    wire::EndHeader header;
    std::array<uint8_t, wire::data_capacity(1)> plain{};
    std::size_t len = 0;
    sec::ReplayVerdict verdict = sec::ReplayVerdict::Fresh;
    [[nodiscard]] ByteView view() const { return ByteView{plain.data(), len}; }
};
// Ok = fresh and authentic (window NOT advanced: the caller runs its checks, then accept()).
// Replay = authentic duplicate (verdict Duplicate) or outside the window. AuthRejected: wrong tag,
// including "same counter, different payload".
[[nodiscard]] Status open_end_record(sec::RecordSession &rec, const Sha256Digest &ctx_hash,
                                     RootTerm term, ByteView record, OpenedEnd &out);
[[nodiscard]] inline Status open_end_record(EndSession &s, RootTerm term, ByteView record,
                                            OpenedEnd &out) {
    return open_end_record(s.rec, s.ctx_hash, term, record, out);
}

} // namespace lm::delivery
